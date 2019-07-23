module Console

open FSharp.Interop.Compose.System

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

