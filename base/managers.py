from django.contrib.auth.models import BaseUserManager


class Manager(BaseUserManager):
    def create_user(self, email, first_name, last_name, password=None):
        if not email:
            raise ValueError("User must have an Email Address")

        user = self.model(
            email = self.normalize_email(email),
            first_name = first_name, 
            last_name = last_name
        )

        user.set_password(password)

        user.save(using=self._db)
        return user

    def create_superuser(self, email, first_name, last_name, password=None):
        user = self.create_user(
            email,
            first_name,
            last_name,
            password=password
        )

        user.is_admin = True
        user.save(using=self._db)
        return user
