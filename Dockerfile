FROM rust:1.81.0

WORKDIR /usr/src/uniswapv4-challenge-miner
COPY . .

RUN cargo install --path .

CMD ["uniswapv4-challenge-miner", "-t", "0"]