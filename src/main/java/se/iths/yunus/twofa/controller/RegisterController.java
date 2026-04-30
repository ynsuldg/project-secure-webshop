package se.iths.yunus.twofa.controller;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.yunus.twofa.model.AppUser;
import se.iths.yunus.twofa.repository.AppUserRepository;
import se.iths.yunus.twofa.service.QrCodeService;
import se.iths.yunus.twofa.service.TwoFactorService;

@Controller
public class RegisterController {

    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;
    private final QrCodeService qrCodeService;

    public RegisterController(AppUserRepository repository,
                              PasswordEncoder passwordEncoder,
                              TwoFactorService twoFactorService,
                              QrCodeService qrCodeService) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.twoFactorService = twoFactorService;
        this.qrCodeService = qrCodeService;
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String email,
                           @RequestParam String password,
                           @RequestParam(required = false) boolean enable2fa,
                           Model model) {

        if (repository.findByEmail(email).isPresent()) {
            model.addAttribute("error", "Email already exists.");
            return "register";
        }

        AppUser user = new AppUser();
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setTwoFactorEnabled(enable2fa);

        if (enable2fa) {
            String secret = twoFactorService.generateSecret();
            user.setTwoFactorSecret(secret);

            repository.save(user);

            String qrUrl = twoFactorService.generateQrUrl(email, secret);
            String qrCode = qrCodeService.generateQrCodeBase64(qrUrl);

            model.addAttribute("qrCode", qrCode);
            model.addAttribute("secret", secret);
            return "show-qr";
        }

        repository.save(user);
        return "redirect:/login";
    }
}