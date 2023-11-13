
using User.Mgmt.Service.Models;

namespace User.Mgmt.Service.Services
{
    public interface IEmailServices
    {
        void SendEmail(Message message);
    }
}
