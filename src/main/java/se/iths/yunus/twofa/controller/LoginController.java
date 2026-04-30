package se.iths.yunus.twofa.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import se.iths.yunus.twofa.model.AppUser;
import se.iths.yunus.twofa.repository.AppUserRepository;
import se.iths.yunus.twofa.service.TwoFactorService;

import java.util.List;

@Controller
public class LoginController {

    private final AppUserRepository repository;
    private final PasswordEncoder passwordEncoder;
    private final TwoFactorService twoFactorService;
    private final SecurityContextRepository securityContextRepository =
            new HttpSessionSecurityContextRepository();

    public LoginController(AppUserRepository repository,
                           PasswordEncoder passwordEncoder,
                           TwoFactorService twoFactorService) {
        this.repository = repository;
        this.passwordEncoder = passwordEncoder;
        this.twoFactorService = twoFactorService;
    }

    @GetMapping("/")
    public String home() {
        return "home";
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        return "login";
    }

    @PostMapping("/login")
    public String login(@RequestParam String email,
                        @RequestParam String password,
                        HttpServletRequest request,
                        HttpServletResponse response,
                        Model model) {

        AppUser user = repository.findByEmail(email).orElse(null);

        if (user == null) {
            model.addAttribute("error", "User not found.");
            return "login";
        }

        if (!passwordEncoder.matches(password, user.getPassword())) {
            model.addAttribute("error", "Wrong password.");
            return "login";
        }

        if (user.isTwoFactorEnabled()) {
            HttpSession session = request.getSession(true);
            session.setAttribute("2fa_user_email", user.getEmail());
            return "redirect:/verify-2fa";
        }

        authenticateUser(user, request, response);
        return "redirect:/";
    }

    @GetMapping("/verify-2fa")
    public String verify2faPage(HttpSession session, Model model) {
        String email = (String) session.getAttribute("2fa_user_email");

        if (email == null) {
            model.addAttribute("error", "Session expired. Please log in again.");
            return "login";
        }

        return "verify-2fa";
    }

    @PostMapping("/verify-2fa")
    public String verify2fa(@RequestParam String code,
                            HttpServletRequest request,
                            HttpServletResponse response,
                            Model model) {

        HttpSession session = request.getSession(false);

        if (session == null) {
            model.addAttribute("error", "Session expired. Please log in again.");
            return "login";
        }

        String email = (String) session.getAttribute("2fa_user_email");

        if (email == null) {
            model.addAttribute("error", "Session expired. Please log in again.");
            return "login";
        }

        AppUser user = repository.findByEmail(email).orElse(null);

        if (user == null || user.getTwoFactorSecret() == null) {
            model.addAttribute("error", "Could not verify user.");
            return "login";
        }

        if (!code.matches("\\d{6}")) {
            model.addAttribute("error", "Code must be exactly 6 digits.");
            return "verify-2fa";
        }

        boolean valid = twoFactorService.verifyCode(
                user.getTwoFactorSecret(),
                Integer.parseInt(code)
        );

        if (!valid) {
            model.addAttribute("error", "Invalid authentication code. Try again.");
            return "verify-2fa";
        }

        session.removeAttribute("2fa_user_email");
        authenticateUser(user, request, response);

        return "redirect:/";
    }

    private void authenticateUser(AppUser user,
                                  HttpServletRequest request,
                                  HttpServletResponse response) {

        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(
                        user.getEmail(),
                        null,
                        List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()))
                );

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        SecurityContextHolder.setContext(context);

        securityContextRepository.saveContext(context, request, response);
    }
}