from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken

from .models import User


class VerificationRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=150, allow_blank=True, required=False)
    last_name = serializers.CharField(max_length=150, allow_blank=True, required=False)
    password = serializers.CharField(write_only=True, max_length=128)
    password2 = serializers.CharField(write_only=True, max_length=128)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password2": "The passwords don't match"})
        candidate = User(
            email=attrs['email'].strip().lower(),
            first_name=(attrs.get('first_name') or '').strip(),
            last_name=(attrs.get('last_name') or '').strip(),
        )
        validate_password(attrs['password'], user=candidate)
        return attrs


class VerificationConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    # Strictly require exactly 6 digits -- rejects oversized payloads and
    # non-numeric strings before we even hit the DB / password hash call.
    code = serializers.RegexField(
        regex=r'^\d{6}$',
        error_messages={'invalid': 'Enter the 6-digit code from your email.'},
    )


class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()


class PasswordResetConfirmSerializer(serializers.Serializer):
    email = serializers.EmailField()
    # Strictly require exactly 6 digits -- rejects oversized payloads and
    # non-numeric strings before we even hit the DB / password hash call.
    code = serializers.RegexField(
        regex=r'^\d{6}$',
        error_messages={'invalid': 'Enter the 6-digit code from your email.'},
    )
    password = serializers.CharField(write_only=True, max_length=128)
    password2 = serializers.CharField(write_only=True, max_length=128)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password2": "The passwords don't match"})
        validate_password(attrs['password'])
        return attrs


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        attrs[self.username_field] = (attrs.get(self.username_field) or '').strip().lower()
        password = attrs.get('password') or ''
        if len(password) > 128:
            raise serializers.ValidationError(
                self.error_messages['no_active_account'],
                code='no_active_account',
            )
        data = super().validate(attrs)
        data['email'] = self.user.email
        data['first_name'] = self.user.first_name
        data["last_name"] = self.user.last_name
        data['id'] = str(self.user.id)
        return data


class UserSerializer(serializers.ModelSerializer):
    # Tells the frontend whether the user has a usable password set.
    # Google-only accounts (created via set_unusable_password) return False,
    # which lets the UI adapt the Change Password section accordingly.
    has_password = serializers.SerializerMethodField(read_only=True)

    def get_has_password(self, obj):
        return obj.has_usable_password()

    def validate_first_name(self, value):
        return value.strip()

    def validate_last_name(self, value):
        return value.strip()

    class Meta:
        model = User
        fields = ["id", "email", "first_name", "last_name", "date_joined", "has_password"]
        # email is the login identifier and recovery channel -- never let a
        # PATCH request change it. Doing so would allow a stolen 15-minute
        # access token to permanently hijack an account via password reset.
        read_only_fields = ["id", "email", "date_joined", "has_password"]


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        try:
            self.token = RefreshToken(attrs['refresh'])
        except Exception as exc:
            raise serializers.ValidationError("Invalid or expired token") from exc

        request_user = self.context['request'].user
        if str(self.token.get('user_id')) != str(request_user.pk):
            raise serializers.ValidationError("Invalid or expired token")
        return attrs

    def save(self, **kwargs):
        try:
            self.token.blacklist()
        except Exception as exc:
            raise serializers.ValidationError("Invalid or expired token") from exc


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, max_length=128)
    new_password = serializers.CharField(write_only=True, max_length=128)
    new_password2 = serializers.CharField(write_only=True, max_length=128)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError("The passwords do not match")
        if attrs['new_password'] == attrs['old_password']:
            raise serializers.ValidationError(
                {"new_password": "New password must be different from your current password."}
            )
        validate_password(attrs['new_password'], user=self.context.get('user'))
        return attrs


class DeleteAccountSerializer(serializers.Serializer):
    # Password accounts confirm deletion with `password`; Google-only accounts
    # (no usable password) confirm deletion with a 6-digit emailed OTP `code`.
    password = serializers.CharField(
        write_only=True, required=False, allow_blank=True, default='', max_length=128
    )
    code = serializers.RegexField(
        regex=r'^\d{6}$',
        required=False,
        allow_blank=True,
        default='',
        error_messages={'invalid': 'Enter the 6-digit code from your email.'},
    )


class GoogleLoginSerializer(serializers.Serializer):
    """
    Accepts the Google Identity Services ID token (a signed JWT).

    The token is the *only* input we trust: email and name are read from the
    signature-verified token claims server-side, never from the request body, so
    a client cannot assert an identity it does not own.
    """

    credential = serializers.CharField(
        write_only=True,
        max_length=4096,
        trim_whitespace=True,
        error_messages={
            'blank': 'A Google credential is required.',
            'required': 'A Google credential is required.',
        },
    )
