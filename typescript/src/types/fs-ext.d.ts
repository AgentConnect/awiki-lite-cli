declare module "fs-ext" {
  export function flock(
    fd: number,
    flags: "sh" | "ex" | "un" | "shnb" | "exnb",
  ): void;
  export function flock(
    fd: number,
    flags: "sh" | "ex" | "un" | "shnb" | "exnb",
    callback: (err: NodeJS.ErrnoException | null) => void,
  ): void;
}
