import getpass
import hashlib
import inspect
import os
import sys

from .messageparse import MessageParseMethods
from .users import UserMethods
from .. import utils, helpers, errors
from ..tl import types, functions


class AuthMethods(MessageParseMethods, UserMethods):

    # region Public methods

    def start(
            self,
            phone=lambda: input('Please enter your phone (or bot token): '),
            password=lambda: getpass.getpass('Please enter your password: '),
            *,
            bot_token=None, force_sms=False, code_callback=None,
            first_name='New User', last_name='', max_attempts=3):
        if code_callback is None:
            def code_callback():
                return input('Please enter the code you received: ')
        elif not callable(code_callback):
            raise ValueError(
                'The code_callback parameter needs to be a callable '
                'function that returns the code you received by Telegram.'
            )

        if not phone and not bot_token:
            raise ValueError('No phone number or bot token provided.')

        if phone and bot_token and not callable(phone):
            raise ValueError('Both a phone and a bot token provided, '
                             'must only provide one of either')

        coro = self._start(
            phone=phone,
            password=password,
            bot_token=bot_token,
            force_sms=force_sms,
            code_callback=code_callback,
            first_name=first_name,
            last_name=last_name,
            max_attempts=max_attempts
        )
        return (
            coro if self.loop.is_running()
            else self.loop.run_until_complete(coro)
        )

    async def _start(
            self, phone, password, bot_token, force_sms,
            code_callback, first_name, last_name, max_attempts):
        if not self.is_connected():
            await self.connect()

        if await self.is_user_authorized():
            return self

        if not bot_token:
            # Turn the callable into a valid phone number (or bot token)
            while callable(phone):
                value = phone()
                if inspect.isawaitable(value):
                    value = await value

                if ':' in value:
                    # Bot tokens have 'user_id:access_hash' format
                    bot_token = value
                    break

                phone = utils.parse_phone(value) or phone

        if bot_token:
            await self.sign_in(bot_token=bot_token)
            return self

        me = None
        attempts = 0
        two_step_detected = False

        sent_code = await self.send_code_request(phone, force_sms=force_sms)
        sign_up = not sent_code.phone_registered
        while attempts < max_attempts:
            try:
                value = code_callback()
                if inspect.isawaitable(value):
                    value = await value

                if sign_up:
                    me = await self.sign_up(value, first_name, last_name)
                else:
                    # Raises SessionPasswordNeededError if 2FA enabled
                    me = await self.sign_in(phone, code=value)
                break
            except errors.SessionPasswordNeededError:
                two_step_detected = True
                break
            except errors.PhoneNumberOccupiedError:
                sign_up = False
            except errors.PhoneNumberUnoccupiedError:
                sign_up = True
            except (errors.PhoneCodeEmptyError,
                    errors.PhoneCodeExpiredError,
                    errors.PhoneCodeHashEmptyError,
                    errors.PhoneCodeInvalidError):
                print('Invalid code. Please try again.', file=sys.stderr)

            attempts += 1
        else:
            raise RuntimeError(
                '{} consecutive sign-in attempts failed. Aborting'
                .format(max_attempts)
            )

        if two_step_detected:
            if not password:
                raise ValueError(
                    "Two-step verification is enabled for this account. "
                    "Please provide the 'password' argument to 'start()'."
                )

            if callable(password):
                for _ in range(max_attempts):
                    try:
                        value = password()
                        if inspect.isawaitable(value):
                            value = await value

                        me = await self.sign_in(phone=phone, password=value)
                        break
                    except errors.PasswordHashInvalidError:
                        print('Invalid password. Please try again',
                              file=sys.stderr)
                else:
                    raise errors.PasswordHashInvalidError()
            else:
                me = await self.sign_in(phone=phone, password=password)

        return self

    async def sign_in(
            self, phone=None, code=None, *, password=None,
            bot_token=None, phone_code_hash=None):
        me = await self.get_me()
        if me:
            return me

        if phone and not code and not password:
            return await self.send_code_request(phone)
        elif code:
            phone = utils.parse_phone(phone) or self._phone
            phone_code_hash = \
                phone_code_hash or self._phone_code_hash.get(phone, None)

            if not phone:
                raise ValueError(
                    'Please make sure to call send_code_request first.'
                )
            if not phone_code_hash:
                raise ValueError('You also need to provide a phone_code_hash.')

            # May raise PhoneCodeEmptyError, PhoneCodeExpiredError,
            # PhoneCodeHashEmptyError or PhoneCodeInvalidError.
            result = await self(functions.auth.SignInRequest(
                phone, phone_code_hash, str(code)))
        elif password:
            salt = (await self(
                functions.account.GetPasswordRequest())).current_salt
            result = await self(functions.auth.CheckPasswordRequest(
                helpers.get_password_hash(password, salt)
            ))
        elif bot_token:
            result = await self(functions.auth.ImportBotAuthorizationRequest(
                flags=0, bot_auth_token=bot_token,
                api_id=self.api_id, api_hash=self.api_hash
            ))
        else:
            raise ValueError(
                'You must provide a phone and a code the first time, '
                'and a password only if an RPCError was raised before.'
            )

        self._self_input_peer = utils.get_input_peer(
            result.user, allow_self=False
        )
        self._authorized = True
        return result.user

    async def sign_up(self, code, first_name, last_name=''):
        me = await self.get_me()
        if me:
            return me

        if self._tos and self._tos.text:
            if self.parse_mode:
                t = self.parse_mode.unparse(self._tos.text, self._tos.entities)
            else:
                t = self._tos.text
            sys.stderr.write("{}\n".format(t))
            sys.stderr.flush()

        result = await self(functions.auth.SignUpRequest(
            phone_number=self._phone,
            phone_code_hash=self._phone_code_hash.get(self._phone, ''),
            phone_code=str(code),
            first_name=first_name,
            last_name=last_name
        ))

        if self._tos:
            await self(
                functions.help.AcceptTermsOfServiceRequest(self._tos.id))

        self._self_input_peer = utils.get_input_peer(
            result.user, allow_self=False
        )
        self._authorized = True
        return result.user

    async def send_code_request(self, phone, *, force_sms=False):
        """
        Sends a code request to the specified phone number.

        Args:
            phone (`str` | `int`):
                The phone to which the code will be sent.

            force_sms (`bool`, optional):
                Whether to force sending as SMS.

        Returns:
            An instance of :tl:`SentCode`.
        """
        phone = utils.parse_phone(phone) or self._phone
        phone_hash = self._phone_code_hash.get(phone)

        if not phone_hash:
            try:
                result = await self(functions.auth.SendCodeRequest(
                    phone, self.api_id, self.api_hash))
            except errors.AuthRestartError:
                return self.send_code_request(phone, force_sms=force_sms)

            self._tos = result.terms_of_service
            self._phone_code_hash[phone] = phone_hash = result.phone_code_hash
        else:
            force_sms = True

        self._phone = phone

        if force_sms:
            result = await self(
                functions.auth.ResendCodeRequest(phone, phone_hash))

            self._phone_code_hash[phone] = result.phone_code_hash

        return result

    async def log_out(self):
        """
        Logs out Telegram and deletes the current ``*.session`` file.

        Returns:
            ``True`` if the operation was successful.
        """
        try:
            await self(functions.auth.LogOutRequest())
        except errors.RPCError:
            return False

        await self.disconnect()
        self.session.delete()
        self._authorized = False
        return True

    async def edit_2fa(
            self, current_password=None, new_password=None,
            *, hint='', email=None):
        if new_password is None and current_password is None:
            return False

        pass_result = await self(functions.account.GetPasswordRequest())
        if isinstance(
                pass_result, types.account.NoPassword) and current_password:
            current_password = None

        salt_random = os.urandom(8)
        salt = pass_result.new_salt + salt_random
        if not current_password:
            current_password_hash = salt
        else:
            current_password = (
                pass_result.current_salt
                + current_password.encode()
                + pass_result.current_salt
            )
            current_password_hash = hashlib.sha256(current_password).digest()

        if new_password:  # Setting new password
            new_password = salt + new_password.encode('utf-8') + salt
            new_password_hash = hashlib.sha256(new_password).digest()
            new_settings = types.account.PasswordInputSettings(
                new_salt=salt,
                new_password_hash=new_password_hash,
                hint=hint
            )
            if email:  # If enabling 2FA or changing email
                new_settings.email = email  # TG counts empty string as None
            return await self(functions.account.UpdatePasswordSettingsRequest(
                current_password_hash, new_settings=new_settings
            ))
        else:  # Removing existing password
            return await self(functions.account.UpdatePasswordSettingsRequest(
                current_password_hash,
                new_settings=types.account.PasswordInputSettings(
                    new_salt=bytes(),
                    new_password_hash=bytes(),
                    hint=hint
                )
            ))

    # endregion

    # region with blocks

    def __enter__(self):
        return self.start()

    async def __aenter__(self):
        return await self.start()

    def __exit__(self, *args):
        if self._loop.is_running():
            self._loop.create_task(self.disconnect())
        elif inspect.iscoroutinefunction(self.disconnect):
            self._loop.run_until_complete(self.disconnect())
        else:
            self.disconnect()

    async def __aexit__(self, *args):
        await self.disconnect()

    # endregion
