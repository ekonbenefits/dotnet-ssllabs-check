// Learn more about F# at http://fsharp.org

open System
open McMaster.Extensions.CommandLineUtils

let OptionToOption (opt:CommandOption<'T>) =
    if opt.HasValue() then
        opt.ParsedValue |> Some
    else
        None

[<EntryPoint>]
let main argv =
    use app = new CommandLineApplication();
    app.HelpOption() |> ignore;
    let optOutDir = app.Option<string>("-o|--output <DIRECTORY>", "Output Directory for optional json data [Default: don't write out data]", CommandOptionType.SingleValue)
    let hosts = app.Argument<string>("Hosts", "Hosts to check SSL Grades and Validity", multipleValues=true).IsRequired();


    app.OnExecute(Func<int>(
                    fun ()->
                       hosts.Values
                       |> Check.sslLabs (optOutDir |> OptionToOption) 
                       |> Async.RunSynchronously
                    ))

    app.Execute(argv)
