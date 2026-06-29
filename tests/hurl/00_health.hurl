GET {{base_url}}/health

[Asserts]
status == 200
jsonpath "$.success" == true
jsonpath "$.data.status" == "ok"
jsonpath "$.data.version" isString
jsonpath "$.data.uptime" isString
