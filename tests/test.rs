#[cfg(test)]
mod tests {
    // Import the functions we want to test from the lib
    use omnirun::{expand_host, hostspec_to_user_pass_host_port, rc_parse};

    #[test]
    fn test_expand_host() {
        // Test expanding a host with range
        let hosts = expand_host("192.168.100.[1-100]").expect("Failed to expand host");
        assert_eq!(hosts.len(), 100);

        // Test that a host without brackets returns a single item
        let hosts = expand_host("example.com").expect("Failed to expand host");
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0], "example.com");

        // Test with multiple ranges
        let hosts = expand_host("server[1-3,5,7-9].example.com").expect("Failed to expand host");
        assert_eq!(hosts.len(), 7); // 3 from range 1-3, 1 from '5', 3 from range 7-9
        assert!(hosts.contains(&"server1.example.com".to_string()));
        assert!(hosts.contains(&"server5.example.com".to_string()));
        assert!(hosts.contains(&"server9.example.com".to_string()));
    }

    #[test]
    fn test_hostspec_to_user_pass_host_port() {
        // Test full hostspec with user, password, host, and port
        let result = hostspec_to_user_pass_host_port("user:pass@host:4444")
            .expect("Failed to parse hostspec");
        assert_eq!(
            result,
            (
                Some("user".to_string()),
                Some("pass".to_string()),
                Some("host".to_string()),
                Some(4444)
            )
        );

        // Test hostspec with user, host, and port (no password)
        let result =
            hostspec_to_user_pass_host_port("user@host:4444").expect("Failed to parse hostspec");
        assert_eq!(
            result,
            (
                Some("user".to_string()),
                None,
                Some("host".to_string()),
                Some(4444)
            )
        );

        // Test hostspec with host and port (no user or password)
        let result =
            hostspec_to_user_pass_host_port("host:4444").expect("Failed to parse hostspec");
        assert_eq!(result, (None, None, Some("host".to_string()), Some(4444)));

        // Test hostspec with just host (no user, password, or port)
        let result = hostspec_to_user_pass_host_port("host").expect("Failed to parse hostspec");
        assert_eq!(result, (None, None, Some("host".to_string()), None));

        // Test empty hostspec
        let result = hostspec_to_user_pass_host_port("").expect("Failed to parse hostspec");
        assert_eq!(result, (None, None, None, None));
    }

    #[test]
    fn test_rc_parse() {
        // Test empty string
        let result = rc_parse(None).expect("Failed to parse rc");
        assert!(result.is_empty());

        // Test "nonzero" option
        let result = rc_parse(Some(&"nonzero".to_string())).expect("Failed to parse rc");
        // Should contain values 1-255
        assert_eq!(result.len(), 255);
        for i in 1..256 {
            assert!(result.contains(&Some(i)));
        }

        // Test "unknown" option
        let result = rc_parse(Some(&"unknown".to_string())).expect("Failed to parse rc");
        assert_eq!(result.len(), 1);
        assert!(result.contains(&None));

        // Test specific values
        let result = rc_parse(Some(&"0,1,2".to_string())).expect("Failed to parse rc");
        assert_eq!(result.len(), 3);
        assert!(result.contains(&Some(0)));
        assert!(result.contains(&Some(1)));
        assert!(result.contains(&Some(2)));

        // Test mixed options
        let result = rc_parse(Some(&"0,unknown,nonzero".to_string())).expect("Failed to parse rc");
        assert_eq!(result.len(), 257); // 0, None, and 1-255
        assert!(result.contains(&Some(0)));
        assert!(result.contains(&None));
        for i in 1..256 {
            assert!(result.contains(&Some(i)));
        }
    }
}

