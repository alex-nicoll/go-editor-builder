# multi-life-dev-builder

This repository implements a minimal build server for [multi-life-dev](https://github.com/alex-nicoll/multi-life-dev).

When there is a change to a file that the multi-life-dev Docker image depends on (located in [multi-life](https://github.com/alex-nicoll/multi-life) or [multi-life-dev](https://github.com/alex-nicoll/multi-life-dev)), the server is notified via a GitHub Webhook. The server then builds and pushes a new image to Docker Hub.
