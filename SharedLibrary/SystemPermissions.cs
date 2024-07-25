namespace SharedLibrary
{
    public enum SystemPermissions
    {
        //Account
        GetAllUsers, GetUserById, Register,
        //Role
        GetAllRoles, GetRoleById, CreateRole, UpdateRole, DeleteRole,
        // UserRole
        AssignRolesToUser, RetrieveRolesOfUser,
        // RolePermission
        AssignPermissionsToRole, RetrievePermissionsOfRole
    }
}