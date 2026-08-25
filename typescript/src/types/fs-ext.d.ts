declare module "fs-ext" {
  export function flockSync(
    fd: number,
    flags: "sh" | "ex" | "un" | "shnb" | "exnb",
  ): void;
}
