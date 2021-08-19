FROM python:3.9 AS builder

WORKDIR /build

# Install mkdocs requirements
COPY requirements.txt ./
RUN python -m pip install --upgrade pip && \
    pip3 install -r requirements.txt

# Build docs page
COPY . ./
RUN mkdocs build

# Copy build to go-static server image
FROM pierrezemb/gostatic:latest
COPY --from=builder /build/site /srv/http
