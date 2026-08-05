from awiki_lite_cli.infrastructure.anp_sdk import sdk_info


def test_anp_sdk_is_local_compatible_release_without_e2ee_profiles() -> None:
    info = sdk_info()

    assert info.version == "0.9.1"
    assert info.allowed_profiles
    assert all("e2ee" not in profile for profile in info.allowed_profiles)
