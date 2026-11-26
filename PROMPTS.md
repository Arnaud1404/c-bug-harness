# Prompts

These are the prompts that shaped this repository, taken from the Claude Code session. Quotes are trimmed and edited for spelling and tone, and the meaning is unchanged. The analyser image predates this repository: its commits come from c-secure-build and keep their dates.

**Involvement:** the harness design comes from a whiteboard drawn with my tutor, Emmanuel Fleury, on 26 November 2026. Claude Code wrote the harness code, the agent prompts and the revised proposal. I chose the scope and the models. I have not yet reread the harness line by line.

## 26 November 2026: from the whiteboard to a repository

- "Fleury detected the AI slop because I didn't clarify the boucle agentique. He wants dedicated skills with separate agents for dedicated tasks, akin to this picture, and somewhat close to LLM council in the idea. Review the proposition and make sure everything is set up correctly. Semgrep is a bit sloppy, he knows people from Infer, he's not familiar with CodeQL."
- "Also make sure everything is actually in the repo. He flagged me when the agentic loop didn't contain any .md files."
- The whiteboard: CASTLE, tools, triage, verifier, checker, editor/writer, `REPORT.md`, a box for rejected findings, and the models Qwen3.5:9b and Gemma4:e4b. The note: "If we can run the first 4 it's fine. The actual agentic loop, Fleury said we can put it where it's best, maybe between verifier and checker. Inspire yourself from CASTLE's way of doing schematics."
- On the models: "Local to test actual token usage, then we check Gemini 4 Hydrogen." On the loop: "Make it all reproducible simply, even on a local machine, so maybe own Python loop."
- "What does c-secure-build have to do with all that? We only have a few checkers, running on a small shell with planted bugs. Judge if it's worth having a separate repo for that." This led to this repository.
- "Do not implement the actual proposition, just make an updated version in its own repo." The model runs were stopped at that point. Only the code the proposal cites was kept.
- "Find good research about making such agentic pipelines, especially on C code", then "just document which ones are worth taking inspiration from for the build, quote them". This produced `docs/related-work.md`.
