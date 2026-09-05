# Hugging Face rotation guide (for how-to-rotate)

This folder is a drop-in contribution for [trufflesecurity/how-to-rotate](https://github.com/trufflesecurity/how-to-rotate). This agent could not push a branch to that repository (`cursor[bot]` has no write or fork permission there).

Copy the files into a how-to-rotate checkout so they match the live site layout:

```
content/docs/tutorials/huggingface.md
content/docs/introduction/_table.md
themes/compose/static/images/huggingface/1.png
themes/compose/static/images/huggingface/2.png
themes/compose/static/images/huggingface/3.png
```

CI regenerates the intro table with `python generate-table.py` on deploy, so `_table.md` only needs to include Hugging Face for local previews.

Screenshots are Hugging Face's official Access Tokens UI images from the [User access tokens](https://huggingface.co/docs/hub/security-tokens) docs.
