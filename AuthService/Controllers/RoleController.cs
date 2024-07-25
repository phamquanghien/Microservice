using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SharedLibrary;

namespace AuthService.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class RoleController : ControllerBase
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        public RoleController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        [Authorize(Policy = nameof(SystemPermissions.GetAllRoles))]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<IdentityRole>>> GetAllRoles()
        {
            return Ok(await _roleManager.Roles.ToListAsync());
        }
        [Authorize(Policy = nameof(SystemPermissions.GetRoleById))]
        [HttpGet("{id}")]
        public async Task<ActionResult<IdentityRole>> GetRoleById(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound();
            }
            return Ok(role);
        }
        [Authorize(Policy = nameof(SystemPermissions.CreateRole))]
        [HttpPost]
        public async Task<ActionResult> CreateRole([FromBody] string roleName)
        {
            if (string.IsNullOrEmpty(roleName))
            {
                return BadRequest("Role name cannot be empty.");
            }

            var roleExists = await _roleManager.RoleExistsAsync(roleName);
            if (roleExists)
            {
                return BadRequest("Role already exists.");
            }

            var result = await _roleManager.CreateAsync(new IdentityRole(roleName));
            if (result.Succeeded)
            {
                return Ok("Role created successfully.");
            }
            return BadRequest(result.Errors);
        }
        [Authorize(Policy = nameof(SystemPermissions.UpdateRole))]
        [HttpPut("{id}")]
        public async Task<ActionResult> UpdateRole(string id, [FromBody] string newRoleName)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found.");
            }

            role.Name = newRoleName;
            var result = await _roleManager.UpdateAsync(role);
            if (result.Succeeded)
            {
                return Ok("Role updated successfully.");
            }
            return BadRequest(result.Errors);
        }
        [Authorize(Policy = nameof(SystemPermissions.DeleteRole))]
        [HttpDelete("{id}")]
        public async Task<ActionResult> DeleteRole(string id)
        {
            var role = await _roleManager.FindByIdAsync(id);
            if (role == null)
            {
                return NotFound("Role not found.");
            }

            var result = await _roleManager.DeleteAsync(role);
            if (result.Succeeded)
            {
                return Ok("Role deleted successfully.");
            }
            return BadRequest(result.Errors);
        }
    }
}