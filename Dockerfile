FROM cgr.dev/chainguard/chainctl:latest AS chainctl

FROM cgr.dev/andrewd.dev/bun:latest
COPY --from=chainctl /usr/bin/chainctl /usr/local/bin/chainctl
WORKDIR /app
COPY server.js index.html ./
EXPOSE 3000
CMD ["run", "server.js"]
