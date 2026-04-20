FROM cgr.dev/andrewd.dev/bun:latest
WORKDIR /app
COPY server.js index.html ./
EXPOSE 3000
CMD ["run", "server.js"]
