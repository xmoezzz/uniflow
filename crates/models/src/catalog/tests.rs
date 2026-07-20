#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn python_models_include_django_terminals_and_session_mutators() {
        let rules = default_models_for(Language::Python);
        let ids = rules
            .summaries
            .iter()
            .map(|rule| rule.id.as_str())
            .collect::<HashSet<_>>();
        assert!(ids.contains("python-django-queryset-terminals"));
        assert!(ids.contains("python-sqlalchemy-session-mutators"));
    }
}
