module Console

open FSharp.Interop.Compose.System
open System

[<Flags>]
type Status = Okay = 0 
                   | Expiring = 1 
                   | GradeB = 2 
                   | CertIssue = 4 
                   | JsonPathWarn = 8
                   // Gap to add More Warnings in the future
                   | Warn = 512 // Warn is < Warn
                   | Error = 1024 // Error is > Error
                   | NotGradeAOrB = 2048 
                   | Expired = 4096 
                   | ExceptionThrown = 8192
                   | JsonPathError = 16384

[<RequireQualifiedAccess>]
type Level = 
    Error
    | Warn
    | Info
    | Progress
    | Debug
    | Trace

let parseConsoleError = 
    String.toLower >>
    function | "error" -> Level.Error 
             | "warn" -> Level.Warn
             | "trace" -> Level.Trace 
             | "debug" -> Level.Debug
             | "progress" -> Level.Progress 
             | _ -> Level.Info

let levelForStatus status =
    if status = Status.Okay then
        Level.Info
    elif status <= Status.Warn then
        Level.Warn
    else
        Level.Error

//Setup Console initial state and functions
let originalColor = Console.ForegroundColor
type ResultStream =
    | NoOp
    | ConsoleColorText of string * ConsoleColor
    | AddStatus of Status
let private consoleStreamWriter (lineEnd:string) (color:ConsoleColor)  fmt =
    let write (s:string) =
        ConsoleColorText(s + lineEnd, color)
    Printf.kprintf write fmt
let consoleN fmt = consoleStreamWriter Environment.NewLine originalColor fmt
let consoleNN fmt = consoleStreamWriter (Environment.NewLine + Environment.NewLine) originalColor fmt 
let console fmt = consoleStreamWriter String.Empty originalColor fmt 
let consoleColorN color fmt = consoleStreamWriter Environment.NewLine color fmt 
let consoleColorNN color fmt = consoleStreamWriter (Environment.NewLine + Environment.NewLine)  color fmt 
let consoleColor color fmt = consoleStreamWriter String.Empty color fmt 
let private consoleMonitor = obj()
let stdoutOrStatusBy (optLevel, specifiedLevel) (result:ResultStream) =
    match result with
    | ConsoleColorText(s, color) ->
        if specifiedLevel <= optLevel then
            lock(consoleMonitor) (
                fun () ->
                    Console.ForegroundColor <- color
                    Console.Write(s)
                    Console.ForegroundColor <- originalColor
            )
        None
    | AddStatus e -> Some e
    | NoOp  -> None
let stdoutBy (optLevel, specifiedLevel) (result:ResultStream) =
    result |> stdoutOrStatusBy (optLevel, specifiedLevel) |> ignore