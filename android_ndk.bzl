load("@rules_android_ndk//:rules.bzl", "android_ndk_repository")

_DEFAULT_API_LEVEL = 28

def _android_ndk_extension_impl(module_ctx):
    api_level = module_ctx.getenv("ANDROID_NDK_API_LEVEL", "") or str(_DEFAULT_API_LEVEL)
    if not api_level.isdigit():
        fail("ANDROID_NDK_API_LEVEL must be a number, got '" + api_level + "'")
    android_ndk_repository(
        name = "androidndk",
        path = module_ctx.getenv("ANDROID_NDK_HOME", ""),
        api_level = int(api_level),
    )

android_ndk = module_extension(
    implementation = _android_ndk_extension_impl,
    doc = "The NDK toolchain; see the comment at the top.",
)
