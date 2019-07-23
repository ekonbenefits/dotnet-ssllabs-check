module Json
#nowarn "44"  //need Jmes.Transform with JToken since we are annotating it with custom functions

open System
open DevLab.JmesPath
open Newtonsoft.Json.Linq
open FSharp.Interop.NullOptAble

type IJsonDocument = FSharp.Data.Runtime.BaseTypes.IJsonDocument

module JToken = 
    let isNullOrEmpty (token:JToken) =
        (token = null) ||
        (token.Type = JTokenType.Array && not token.HasValues) ||
        (token.Type = JTokenType.Object && not token.HasValues) ||
        (token.Type = JTokenType.String && token.ToString() = String.Empty) ||
        (token.Type = JTokenType.Null)

let toIJsonDocOption target : IJsonDocument option =
    target |> Option.map (fun x-> upcast x)

let jmes = 
    let jmes' = JmesPath()
    jmes'.FunctionRepository
         .Register<Console.Error>()
         .Register<Console.Warn>()
         .Register<Console.Info>()
         .Register<Console.Progress>()
         .Register<Console.Debug>()
         .Register<Console.Trace>() |> ignore
    jmes'

    
let queryJmesPath q (json:JToken) =
    jmes.Transform(json, q) |> Option.ofObjWhenNot JToken.isNullOrEmpty
    