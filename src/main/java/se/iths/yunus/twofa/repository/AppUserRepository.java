package se.iths.yunus.twofa.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import se.iths.yunus.twofa.model.AppUser;

import java.util.Optional;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    Optional<AppUser> findByEmail(String email);
}