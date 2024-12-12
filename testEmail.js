const nodemailer = require('nodemailer');
require('dotenv').config();

async function sendTestEmail() {
  console.log("Email User:", process.env.EMAIL_USER);  // Debugging
  console.log("Email Pass:", process.env.EMAIL_PASS);  // Debugging

  let transporter = nodemailer.createTransport({
    host: 'smtp.mail.yahoo.com',
    port: 465,
    secure: true, // Use TLS
    auth: {
      user: process.env.EMAIL_USER,  // Your Yahoo email
      pass: process.env.EMAIL_PASS   // Your app-specific password
    },
    debug: true,  // Enable SMTP debug output
    logger: true  // Log to console
  });

  try {
    let info = await transporter.sendMail({
      from: process.env.EMAIL_USER,  // Sender address
      to: process.env.COMPANY_EMAIL, // Receiver's email
      subject: "Test Email from Yahoo",  // Subject line
      text: "Hello, this is a test email from Yahoo!"  // Plain text body
    });

    console.log("Message sent: %s", info.messageId);
  } catch (error) {
    console.error("Error sending email: ", error);
  }
}

sendTestEmail();
