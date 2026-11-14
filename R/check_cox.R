# The Cox model of unscheduled, checked in R (evaluation/phase2_plan.yaml, survival_r_check).
#
#     Rscript R/check_cox.R <design.csv> <result.json>
#
# Fits survival::coxph without a penalty to the design matrix lifelines fit, with Efron's method for
# tied times as lifelines uses it, and writes the coefficients, Harrell's concordance and the
# versions of R and of the survival package as JSON. scripts/train_survival.py compares them with
# lifelines within the plan's tolerances.
args <- commandArgs(trailingOnly = TRUE)
if (length(args) != 2) stop("usage: Rscript R/check_cox.R <design.csv> <result.json>")
suppressPackageStartupMessages(library(survival))
data <- read.csv(args[1], check.names = FALSE)
covariates <- setdiff(names(data), c("duration", "event"))
terms <- paste(sprintf("`%s`", covariates), collapse = " + ")
fit <- coxph(as.formula(paste("Surv(duration, event) ~", terms)), data = data, ties = "efron")
coefs <- coef(fit)
names(coefs) <- gsub("`", "", names(coefs))
if (any(is.na(coefs))) stop("coxph left a coefficient undefined: the design has a collinear column")
quote <- function(x) paste0("\"", gsub("\"", "\\\\\"", x), "\"")
entries <- paste(sprintf("%s: %s", quote(names(coefs)), formatC(coefs, digits = 17, format = "g")), collapse = ", ")
json <- sprintf(
  "{\"coefficients\": {%s}, \"concordance\": %s, \"events\": %d, \"rows\": %d, \"r_version\": %s, \"survival_version\": %s}",
  entries,
  formatC(unname(concordance(fit)$concordance), digits = 17, format = "g"),
  as.integer(fit$nevent),
  as.integer(fit$n),
  quote(R.version.string),
  quote(as.character(packageVersion("survival")))
)
writeLines(json, args[2])
cat(sprintf("check_cox: %d coefficients, concordance %.4f, %s\n", length(coefs), concordance(fit)$concordance, R.version.string))
