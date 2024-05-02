wrk.method = "GET"
wrk.headers["Accept-Encoding"] = "gzip"

request = function()
    return wrk.format("GET", "/index.html")
end
