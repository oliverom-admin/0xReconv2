# recon-worker

The worker runs using the same Docker image as recon-api.
It uses a different CMD that starts the SchedulerService loop.
There is no separate Dockerfile — see packages/recon-api/Dockerfile.
The worker service in docker-compose.yml overrides CMD.
