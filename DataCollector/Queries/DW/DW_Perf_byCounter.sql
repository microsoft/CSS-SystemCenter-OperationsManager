/*Top 30 performance insertions: */
select TOP 30 PR.CounterName,PR.ObjectName, vR.ruledefaultname As RuleName, COUNT(PR.countername) AS Total
from Perf.vPerfRaw perf
join ManagedEntity ME WITH(NOLOCK) on perf.ManagedEntityRowId = ME.ManagedEntityRowId
join PerformanceRuleInstance PRI WITH(NOLOCK) on perf.PerformanceRuleInstanceRowId = PRI.PerformanceRuleInstanceRowId
join PerformanceRule PR WITH(NOLOCK) on PRI.RuleRowId = PR.RuleRowId
join vRule vR on vR.rulerowid = PR.RuleRowId
where perf.DateTime > GetUTCDate() -48
GROUP BY PR.ObjectName, PR.CounterName, vr.ruledefaultname
ORDER BY COUNT (PR.CounterName) dESC