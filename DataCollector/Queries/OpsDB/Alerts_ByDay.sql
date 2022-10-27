﻿SELECT CONVERT(VARCHAR(20), TimeAdded, 102) AS DayAdded, COUNT(*) AS NumAlertsPerDay 
FROM AlertView
WHERE TimeRaised is not NULL 
GROUP BY CONVERT(VARCHAR(20), TimeAdded, 102) 
ORDER BY DayAdded DESC