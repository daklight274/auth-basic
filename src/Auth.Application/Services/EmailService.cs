using Auth.Application.IServices;
using Auth.Application.Settings;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Text;
using System.Threading.Tasks;

namespace Auth.Application.Services
{
    public class EmailService : IEmailService
    {
        private readonly SmtpSettings _smtp;
        private readonly ILogger<EmailService> _logger;

        public EmailService(IOptions<SmtpSettings> smtp, ILogger<EmailService> logger)
        {
            _smtp = smtp.Value;
            _logger = logger;
        }

        public async Task SendVerificationCodeAsync(string toEmail, string code)
        {
            try
            {
                using var client = new SmtpClient(_smtp.Host, _smtp.Port)
                {
                    EnableSsl = _smtp.EnableSsl,
                    Credentials = new NetworkCredential(_smtp.Username, _smtp.Password)
                };

                var message = new MailMessage
                {
                    From = new MailAddress(_smtp.FromEmail, _smtp.FromName),
                    Subject = "Your verification code",
                    IsBodyHtml = true,
                    Body = $"""
                    <div style="font-family:sans-serif;max-width:480px;margin:auto">
                      <h2>Email Verification</h2>
                      <p>Use the code below to activate your account. It expires in <strong>15 minutes</strong>.</p>
                      <div style="font-size:36px;font-weight:bold;letter-spacing:8px;
                                  padding:20px;background:#f5f5f5;border-radius:8px;
                                  text-align:center">{code}</div>
                      <p style="color:#888;font-size:12px;margin-top:24px">
                        If you did not request this, ignore this email.
                      </p>
                    </div>
                    """
                };
                message.To.Add(toEmail);

                await client.SendMailAsync(message);
                _logger.LogInformation("Verification email sent to {Email}", toEmail);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send verification email to {Email}", toEmail);
                throw;
            }
        }
    }
}
