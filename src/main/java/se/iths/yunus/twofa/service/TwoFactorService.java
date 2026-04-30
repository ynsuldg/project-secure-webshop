package se.iths.yunus.twofa.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import com.warrenstrange.googleauth.GoogleAuthenticatorQRGenerator;
import org.springframework.stereotype.Service;

@Service
public class TwoFactorService {
    private final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();

    public String generateSecret() {
        GoogleAuthenticatorKey key = googleAuthenticator.createCredentials();
        return key.getKey();
    }

    public boolean verifyCode(String secret, int code) {
        return googleAuthenticator.authorize(secret, code);
    }

    public String generateQrUrl(String email, String secret) {
        GoogleAuthenticatorKey key =
                new GoogleAuthenticatorKey.Builder(secret).build();

        return GoogleAuthenticatorQRGenerator.getOtpAuthURL(
                "Yunus-VG-2FA",
                email,
                key
        );
    }
}