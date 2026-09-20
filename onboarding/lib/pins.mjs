// Third-party actions used by GENERATED consumer workflows, pinned by full
// commit SHA exactly as the framework's own examples pin them (a test asserts
// the two never drift). Upgrading one is a reviewed change here.
export const ACTIONS = {
  checkout: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1',
  setupBuildx: 'docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e # v4.3.0',
  buildPush: 'docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a # v7.3.0',
  uploadArtifact: 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1',
  setupNode: 'actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0',
  configureAwsCredentials: 'aws-actions/configure-aws-credentials@cbe3b392738ccf3f987d68400dafcf4b0624a56c # v6.2.4'
};

// Node for the framework's .mjs deploy script — the same tool version the
// reusable workflows default to.
export const NODE_VERSION = '24.21.0';

// Fixed artifact names. Not configurable: nothing gains from renaming them, and
// every link in the digest chain refers to them.
export const IMAGE_TARBALL = 'application-image.tar';
export const imageArtifact = () => 'application-image-${{ github.sha }}';
