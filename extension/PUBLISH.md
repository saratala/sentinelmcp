# Publishing SentinelMCP to the VS Code Marketplace

Follow these steps to publish a new release.

## One-time setup

1. Go to https://marketplace.visualstudio.com/manage
2. Sign in with a Microsoft account.
3. Create a publisher named **sentinelmcp** if it does not already exist.
4. Go to https://dev.azure.com and open your organization's User Settings > Personal Access Tokens.
5. Create a new PAT with the following scope:
   - **Marketplace** → **Manage** (publish scope)
6. Copy the generated token — you will not see it again.

## Publish a release

```bash
VSCE_PAT=<your-token> make extension-publish
```

This compiles the extension, packages it, and pushes it to the Marketplace under the `sentinelmcp` publisher.

## Verify

After publishing, the extension page will be live at:

https://marketplace.visualstudio.com/items?itemName=sentinelmcp.sentinelmcp

Allow a few minutes for the Marketplace to index the new version.
