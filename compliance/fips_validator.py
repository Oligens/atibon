class FipsValidator:
    def validate_provider(self, provider_metadata): return bool(provider_metadata.get('validated_module'))
