# Hugging Face rotation guide (for how-to-rotate)

This folder is a drop-in contribution for [trufflesecurity/how-to-rotate](https://github.com/trufflesecurity/how-to-rotate). This agent could not push a branch to that repository (`cursor[bot]` has no write or fork permission there).

From a how-to-rotate checkout, copy these files from this branch:

```bash
git clone https://github.com/heyfunwhoa/trufflehog.git -b cursor/huggingface-rotation-guide-3dc2 /tmp/huggingface-how-to-rotate
cd /path/to/how-to-rotate
cp /tmp/huggingface-how-to-rotate/contrib/how-to-rotate/content/docs/tutorials/huggingface.md content/docs/tutorials/
cp /tmp/huggingface-how-to-rotate/contrib/how-to-rotate/content/docs/introduction/_table.md content/docs/introduction/
mkdir -p themes/compose/static/images/huggingface
cp /tmp/huggingface-how-to-rotate/contrib/how-to-rotate/themes/compose/static/images/huggingface/*.png themes/compose/static/images/huggingface/
```

CI regenerates the intro table with `python generate-table.py` on deploy, so `_table.md` only needs to include Hugging Face for local previews.

Screenshots are Hugging Face's official Access Tokens UI images from the [User access tokens](https://huggingface.co/docs/hub/security-tokens) docs.
