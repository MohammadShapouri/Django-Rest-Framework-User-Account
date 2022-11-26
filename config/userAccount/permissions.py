from rest_framework.permissions import BasePermission

class AllowOwnersAdmins(BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_authenticated:
            if request.user.is_superuser or request.user.is_staff:
                return True
            elif str(request.user.pk) == str(obj.pk):
                return True
            else:
                return False
        else:
            return False

