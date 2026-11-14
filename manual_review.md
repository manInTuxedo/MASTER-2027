# Manual review of the automatic grading

## 1. Purpose

The grader labels every CVE cited by a model (correct, real but wrong, fabricated, rejected, real but unscored, neutral). This review checks a sample of those labels by hand against the National Vulnerability Database (NVD), to show how far the automatic grading can be trusted. The share of labels that a human reviewer confirms is reported in the paper.

## 2. Files

| Item | Location |
|---|---|
| Sample sheet to fill in | `nmap-lab/grading/manual_review_sample.csv` |
| Column to fill in | `my_check` (the last column) |
| Optional notes column | add a column named `my_note` at the end |
| Script that draws the sample | `nmap-lab/sample_for_review.py` (8 citations per label, seed 7, complete condition, models only) |

Columns of the sheet: `label` (the automatic label), `service_id`, `product`, `detected_version` (the version Nmap reported for the service), `cve_id`, `nvd_page` (link to the NVD page), `model`, `prompt`, `my_check`.

Open the CSV in Excel and save it again as "CSV UTF-8". Do not change the other columns.

## 3. What to do for every row

1. Open the link in `nvd_page`.
2. Note whether the page exists. A CVE that NVD does not know shows a "not found" message.
3. Read the status of the record (for example Analyzed, Awaiting Analysis, Rejected) and the description.
4. If the label depends on the affected versions, scroll to **Known Affected Software Configurations**. Look only at lines marked **Vulnerable**. Lines marked "Running on/with" do not count.
5. Find the product of the service (`product`) and compare the affected versions with `detected_version`. Read the range exactly: "from (including)", "up to (excluding)", "up to (including)", or a single version.
6. Apply the rule for the label (Section 4) and write `yes`, `no`, or `unsure` in `my_check`.
7. For every `no` and `unsure`, write a short reason in `my_note`, with the evidence, for example: `range up to 2.4.48 excluding; detected 2.4.49 is outside`.

Use the NVD page as the only source for the decision. Other sites may be used to understand a description, but not to decide applicability.

Product names in NVD may differ from the scan: nginx can appear as `f5 nginx` or `igor_sysoev nginx`, MySQL as `oracle mysql`, and OpenSSH versions as `8.4` with update `p1`. Treat these as the same product and version as the service. Redis and Apache use the names shown.

## 4. Rule for each label

`yes` means the automatic label is right.

| Label | Mark `yes` if | Mark `no` if | Mark `unsure` if |
|---|---|---|---|
| correct | The CVE exists, is not rejected, and a Vulnerable configuration of the same product includes the detected version. The entry has no version limits at all, and is not tagged disputed. For MySQL, it is not about a third-party library that MySQL bundles. | The detected version is outside every affected range, or the product is different, or the entry has no version limits or is disputed (it should be neutral), or it is a bundled-library CVE (it should be neutral). | NVD has no configuration data, or the data is unclear. |
| real_but_wrong | The CVE exists and is analysed, and no Vulnerable configuration of the same product includes the detected version (different product, or version outside the range). | The detected version is inside an affected range of the same product (it should be correct). | The configuration data is missing or unclear. |
| fabricated | NVD has no record of the CVE. Also check `https://www.cve.org/CVERecord?id=<CVE id>`: if the CVE is not there either, the label is right. | The NVD page exists. | NVD has no record, but the CVE exists on cve.org (it may be too new for NVD). |
| rejected | The NVD status is Rejected, or the description starts with `** REJECT **`. | The CVE is not rejected. | - |
| real_unscored | The CVE exists, and its status is Received, Awaiting Analysis, Undergoing Analysis, or Deferred, or the page has no configuration data. | The CVE has full configuration data and an analysed status. | - |
| neutral | The entry is tagged disputed, or the product has an affected range with no version limits at all, or (MySQL only) the description is about a third-party library bundled with MySQL, such as zlib, OpenSSL, libxml2, curl, lz4, zstd, or protobuf. | None of these applies. | The description is borderline. |

## 5. Rules to keep the review fair

- Review the rows in the order of the sheet, and do not look up what the models answered or what the grader found beyond the sheet.
- Do not change a label because the CVE "looks related" to the product. Decide from the affected versions only.
- If a range is written in two places, use the Vulnerable configuration.
- Write the review date in the file name or in a note (NVD changes over time). The ground truth was retrieved on 2026-11-06.
- A review takes about two minutes per row. Do not leave rows empty: use `unsure`.

## 6. Second reviewer (recommended)

A second author reviews at least 15 rows independently, without seeing the first reviewer's answers. To hide the automatic label from the second reviewer, create a blind copy:

```
python -c "import csv;r=list(csv.DictReader(open('grading/manual_review_sample.csv',encoding='utf-8-sig')));f=[c for c in r[0] if c!='label'];w=csv.DictWriter(open('grading/manual_review_blind.csv','w',newline='',encoding='utf-8-sig'),fieldnames=f,extrasaction='ignore');w.writeheader();w.writerows(r)"
```

If the blind copy is used, the second reviewer must decide the label themselves (correct, real but wrong, fabricated, rejected, unscored, or neutral) in `my_check`, using the rules in Section 4. Agreement is then the share of rows where both reviewers chose the same label as the grader. Report the percentage of agreement (and Cohen's kappa if there are enough rows).

## 7. What to report

After the review, count the rows:

- `yes`, `no`, and `unsure` for each label and in total.
- Agreement = `yes` / (`yes` + `no`), with `unsure` counted separately.
- For every `no`, decide whether the cause is a grader rule, a data problem, or a reviewer mistake. If a grader rule is wrong, tell the team before the numbers are frozen.

The sample has the same number of citations for each label, so the agreement figure describes how reliable each label is. It does not estimate the accuracy over all citations. State this in the paper.

Suggested sentence for the paper: "A stratified sample of N graded citations (n per label) was checked manually against NVD; X agreed with the automatic label, Y disagreed, and Z were unclear."