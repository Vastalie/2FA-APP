const otplib = require('otplib');

test('OTP generation should create a valid OTP', () => {
    const secret = otplib.authenticator.generateSecret();
    const otp = otplib.authenticator.generate(secret);
    expect(otplib.authenticator.check(otp, secret)).toBe(true);
});
