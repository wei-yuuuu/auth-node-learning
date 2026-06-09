export class Semaphore {
  #available;
  #queue = [];

  constructor(limit) {
    if (!Number.isInteger(limit) || limit < 1) {
      throw new TypeError("Semaphore limit must be a positive integer");
    }

    this.#available = limit;
  }

  async run(task) {
    await this.#acquire();

    try {
      return await task();
    } finally {
      this.#release();
    }
  }

  #acquire() {
    if (this.#available > 0) {
      this.#available -= 1;
      return Promise.resolve();
    }

    return new Promise((resolve) => {
      this.#queue.push(resolve);
    });
  }

  #release() {
    const next = this.#queue.shift();

    if (next) {
      next();
      return;
    }

    this.#available += 1;
  }
}
