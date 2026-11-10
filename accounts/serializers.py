from rest_framework import serializers
from .models import User
from django.contrib.auth.password_validation import validate_password
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.tokens import RefreshToken


class RegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password2": "The passwords don't match"})
        validate_password(attrs['password'])
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2")
        return User.objects.create_user(**validated_data)

    class Meta:
        model = User
        extra_kwargs = {
            "password": {"write_only": True}
        }
        fields = ["email", "first_name", "last_name", "password", "password2"]


class VerificationRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()
    first_name = serializers.CharField(max_length=150, allow_blank=True, required=False)
    last_name = serializers.CharField(max_length=150, allow_blank=True, required=False)
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password2": "The passwords don't match"})
        validate_password(attrs['password'])
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
    password = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError({"password2": "The passwords don't match"})
        validate_password(attrs['password'])
        return attrs


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
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
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True)
    new_password2 = serializers.CharField(write_only=True)

    def validate(self, attrs):
        if attrs['new_password'] != attrs['new_password2']:
            raise serializers.ValidationError("The passwords do not match")
        validate_password(attrs['new_password'])
        return attrs


class DeleteAccountSerializer(serializers.Serializer):
    # Optional so Google-only accounts (no usable password) can delete their
    # account. The view still enforces the password for password accounts.
    password = serializers.CharField(write_only=True, required=False, allow_blank=True, default='')


class GoogleLoginSerializer(serializers.Serializer):
    """
    Accepts the Google Identity Services ID token (a signed JWT).

    The token is the *only* input we trust: email and name are read from the
    signature-verified token claims server-side, never from the request body, so
    a client cannot assert an identity it does not own.
    """

    credential = serializers.CharField(
        write_only=True,
        trim_whitespace=True,
        error_messages={
            'blank': 'A Google credential is required.',
            'required': 'A Google credential is required.',
        },
    )
