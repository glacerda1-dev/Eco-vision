use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};

/// Stores only an Argon2id PHC hash; the original password cannot be recovered.
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
}

pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    PasswordHash::new(encoded_hash).ok().is_some_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_is_salted_and_verifiable() {
        let password = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let first_hash = hash_password(&password).unwrap();
        let second_hash = hash_password(&password).unwrap();

        assert!(first_hash.starts_with("$argon2id$"));
        assert_ne!(first_hash, second_hash);
        assert_ne!(first_hash, password);
        assert!(verify_password(&password, &first_hash));
        assert!(!verify_password("incorrect", &first_hash));
    }
}
