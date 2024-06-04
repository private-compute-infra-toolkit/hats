load("@depend_on_what_you_use//:defs.bzl", "dwyu_aspect_factory")

hats_dwyu_aspect = dwyu_aspect_factory(skipped_tags = ["rust-bridge", "grpc"], skip_external_targets = True)
