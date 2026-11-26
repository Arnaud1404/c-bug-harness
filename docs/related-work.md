# Related work: what the build takes from it

Papers and posts that use a model on C code or sanitizer output, kept to the ideas this repository uses or plans to use. Every quote below is verbatim, from the version linked, read on 26 November 2026. The "Taken" line says where the idea lives in this repository, or that it is not built yet.

## LLM4SA: a model inspects static analyser warnings

Wen et al., *Automatically Inspecting Thousands of Static Bug Warnings with Large Language Model: How Far Are We?*, ACM TKDD, 2024, doi:10.1145/3653718. [PDF](https://wcventure.github.io/pdf/TKDD2024_LLM4SA.pdf)

The closest work to the triage agent: Cppcheck, Clang SA and Infer warnings on C/C++, one model call per warning.

> "we convert the bug warning to a customized format in JSON, including six general information: the bug type, the file path, the function name, the error location, the error trace, and the corresponding description." (Section 3.2)

> "LLMs are first required to analyze the behavior of the code, present an explanation regarding the presence or absence of a bug, and finally make an appropriate conclusion." (Section 3.4)

> "showcasing a high precision (81.13%) and a recall rate (94.64%) for a total of 9,547 bug warnings." (Abstract)

> "Llm4saF significantly improves the precision of Llm4saZ across all three static analyzers." (Section 5.4, few-shot against zero-shot)

> "another viable solution is to implement an iterative process. This process enables LLMs to request supplementary information, such as function definitions." (Section 6.2, limitations)

- Taken: one finding format for every analyser (`harness/normalize.py`), and an explanation before the verdict (the `reason` field in `agents/triage.md`).
- Not built yet: few-shot examples per bug type in the triage prompt. LLM4SA's own ablation shows they raise precision. CASTLE programs fit in one file, so the "request more code" loop is not needed here.
- Their leakage argument ("bug warnings ... suffer from low quality and variations, rendering them unsuitable for training") does not carry over: CASTLE programs are public source files.

## LLift: a model rechecks what a static analyser could not decide

Li, Hao, Zhai, Qian, *The Hitchhiker's Guide to Program Analysis: A Journey with Large Language Models*, arXiv:2308.00245 (v3), published at OOPSLA 2024 under another title. [arXiv](https://arxiv.org/abs/2308.00245)

Linux kernel C code, use-before-initialization warnings from UBITect.

> "we only provide function details on demand, i.e., when LLMs are not able to conduct a result immediately." (Section 4.2)

> "Finally, we propose self-validation by requesting LLMs to review responses at various stages" (Section 1)

> "we implement majority voting by running each case multiple times" (Section 4.2)

> "LLMs may create non-existent facts in an attempt to rationalize the original intention behind the problematic code" (Section 1)

> "With 26 positive reports out of nearly 1,000 cases, LLift reaches a high precision of 50%." (Section 1)

- Taken: a separate review step, which here is the checker, a different agent rather than the same model reviewing its own answer.
- Not built yet: majority voting. The proposal only plans a second run on 25 programs to measure the variance between runs.

## LLMSAN: make the model emit a proof, then check the proof

Wang, Zhang, Su, Xu, Zhang, *Sanitizing Large Language Models in Bug Detection with Data-Flow*, Findings of EMNLP 2024. [ACL Anthology](https://aclanthology.org/2024.findings-emnlp.217)

The prototype targets Java, but the checking idea is language-independent.

> "Our key idea is to enforce LLMs to emit data-flow paths in few-shot chain-of-thought prompting and validate them via the program-property decomposition." (Abstract)

> "we further separate syntactic properties from semantic properties. Specifically, the former focuses on properties that can be verified by deterministic algorithms based on parsers" (Section 4)

> "Our approach averagely achieves 91.03% precision and 74.00% recall upon synthetic benchmarks, and boosts the precision by 21.99% with the sanitization." (Abstract)

> "the functionality sanitizer and reachability sanitizer in LLMSAN may erroneously flag valid data-flow paths as spurious." (Section 7, limitations)

- Taken: the checker judges the recorded run output, not the verifier's account of it (`harness/pipeline.py`, `last_run`).
- Not built yet: a deterministic check before the checker agent, for example that the sanitizer report names the reported line. That is the "deterministic part first" split of LLMSAN, done with the sanitizer instead of a parser.

## Project Naptime and Big Sleep: an agent loop with real tools

Glazunov, Brand, *Project Naptime: Evaluating Offensive Security Capabilities of Large Language Models*, Google Project Zero, June 2024. [Post](https://projectzero.google/2024/06/project-naptime.html)

> "Interactivity within the program environment is essential" (Proposed principles, 2)

> "potential solutions can be verified automatically with absolute certainty" (Proposed principles, 4)

> "a sampling strategy that allows models to explore multiple hypotheses through multiple independent trajectories" (Proposed principles, 5)

> "which can be susceptible to plausible but vague explanations of vulnerabilities" (CyberSecEval 2, on judging by a model or a human)

> "it is difficult for smaller models to reliably do all of these things correctly within a single trajectory." (Evaluation)

Big Sleep team, *From Naptime to Big Sleep*, Google Project Zero, November 2024. [Post](https://projectzero.google/2024/10/from-naptime-to-big-sleep.html)

> "it's likely that a target-specific fuzzer would be at least as effective" (Conclusion)

- Taken: the model asks for tools, the harness runs them and returns the real output (`harness/loop.py`), and a crash under ASan or UBSan is the strongest evidence a bug can have.
- Taken: one task per agent. The "single trajectory" remark is the argument for splitting the work when the models are 9B and 4B.
- Not built yet: several independent runs per program (principle 5).

## FuzzingBrain V2: specialised agents and a verifier for C/C++

Sheng, Chen, Xu, Zhu, Huang, *FuzzingBrain V2: A Multi-Agent LLM System for Automated Vulnerability Discovery and Reproduction*, arXiv:2605.21779, 2026. [arXiv](https://arxiv.org/abs/2605.21779)

> "report potential issues liberally, as a dedicated Verifier will filter false positives later." (Section 3.4.3)

> "The Verifier only rejects SPs when 100% certain they are false positives." (Section 3.4.4)

> "We use control-flow descriptions instead of line numbers because LLMs frequently hallucinate exact line numbers." (Section 3.2)

> "FuzzingBrain V2 achieved 90% detection rate (36 of 40 vulnerabilities)" (Abstract, AIxCC 2025 C/C++ set)

- Taken: triage keeps a group unless the code rules it out, and the verifier rejects only on `refuted`.
- Risk for this build: CASTLE scores by line, and the paper says models get line numbers wrong. The prompts show numbered code, and CASTLE's own parser moves a finding to the line whose text the model quotes (`harness/castle.py`). The share of wrong lines should be measured.
- The abstract and the introduction give different zero-day counts (29 in 12 projects, 41 in 19). Neither is cited here.

## SEC-bench: sanitizer reports as the oracle

Lee, Zhang, Lu, Zhang, *SEC-bench: Automated Benchmarking of LLM Agents on Real-World Software Security Tasks*, arXiv:2506.11791 (v2), 2025. [arXiv](https://arxiv.org/abs/2506.11791)

> "sanitizers provide deterministic validation without subjective judgment" (Section 2.1)

> the proof of concept must "trigger the sanitizer to report the correct vulnerability type at expected locations." (Section 2.4)

> "The manager agent oversees the verification process by coordinating specialized sub-agents: builder, exploiter, and fixer." (Section 2.3)

> the manager "provides targeted feedback and reassigns the task to the appropriate sub-agent for improvement" (Section 2.3)

> "at most 18.0% success in PoC generation and 34.0% in vulnerability patching on our complete dataset" (Abstract)

- Taken: the checker's `retry` sends the bug back to the verifier with a reason, and the loop is capped (`MAX_ROUNDS = 2`).
- Not built yet: matching the type and location of the sanitizer report against the CASTLE ground truth before scoring a `confirmed` verdict.

## Synthesizing Multi-Agent Harnesses for Vulnerability Discovery

Liu, Shou, Liu, Wen, Chen, Fang, Feng, arXiv:2604.20801, 2026. [arXiv](https://arxiv.org/abs/2604.20801)

The paper is about searching for good agent topologies. Its worked example is close to Fleury's board.

> "iteration 3 adds a verifier with AddressSanitizer and a retry loop, triggering the heap-buffer-overflow." (Figure 1 caption)

> "with the verifier's verdict feeding back to the analyst on failure" (Section 1)

> "Different agents in the same harness may use different LLM models." (Section 4.1)

- Taken: the verifier with ASan and a retry loop.
- Not built yet: the checker on a different model from the verifier, which is the LLM-council idea Fleury mentioned. `harness/loop.py` reads one server URL, so it needs a second URL per agent.

## Found but not used for the build

- IRIS (ICLR 2025): it writes CodeQL specifications for Java. It is out of scope here, because there is no CodeQL and no Java.
- PrimeVul (ICSE 2025, [arXiv](https://arxiv.org/abs/2403.18624)): a 7B model that scores well on BigVul collapses on cleanly labelled C/C++ functions. This belongs in the report's limits, not in the build, and the paper was not read in full.
