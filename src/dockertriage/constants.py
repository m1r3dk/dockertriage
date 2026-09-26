"""Registry endpoints, media types and tunables.

Kept in one module so a new registry or media type is a single-file change.
"""

DOCKERHUB_REGISTRY = "registry-1.docker.io"
DOCKERHUB_TOKEN_URL = "https://auth.docker.io/token"
ECR_PUBLIC_REGISTRY = "public.ecr.aws"
ECR_PUBLIC_TOKEN_URL = "https://public.ecr.aws/token/"

MANIFEST_ACCEPT = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
INDEX_TYPES = {
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.index.v1+json",
}

USER_AGENT = "dockertriage/1.0 (+stdlib)"
CHUNK = 1 << 20  # 1 MiB

# Where a batch run drops its folders when no -o is given: one image can
# reasonably land in the cwd, but a list of 500 must not litter it.
BATCH_OUTPUT_DIR = "output"

# The per-image record a finished pull leaves in its destination folder. Its
# presence is the completion marker `dt verify` reads, so the name is shared
# rather than spelled out at each use site.
IMAGE_META_NAME = ".image.json"
# Raw layer tarballs, kept only with --keep-tar. Not part of the rootfs, so
# verification counts must exclude it.
LAYER_CACHE_NAME = ".layers"

# Where a batch writes the images it could not download. A count is not
# actionable on its own, so the names go somewhere the user can act on.
SKIPPED_FILE_NAME = "not-downloaded.txt"
