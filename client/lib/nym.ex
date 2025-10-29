defmodule Nym do
  @moduledoc """
  Identity provider and authentication layer.

  Nym is a minimal IndieAuth implementation providing an authorization endpoint, which serves two purposes:

  1. decentralised authentication using personal domain names as identity, following the [IndieAuth specification](https://indieauth.spec.indieweb.org/).
  2. centralised authentication layer for in-house applications (similar to OAuth or SSO).

  This library provides a Nym client for easily protecting Phoenix-based applications with centralised identity management.

  ## Usage

      import Nym

      pipeline :browser do
        ...
        plug :fetch_session
        plug :fetch_current_user
      end

      scope "/protected" do
        pipe_through [:browser, :require_auth]

        get "/", PageController, :index

        live_session :default, on_mount: Nym do
          live "/hello", WorldLive, :hello
        end
      end

  """

  import Plug.Conn
  import Phoenix.Controller

  require Logger

  @type opts :: [
          on: String.t(),
          scopes: [String.t()]
        ]

  @doc false
  def on_mount(_, _params, session, socket) do
    user = Map.get(session, "current_user")

    {:cont, socket
     |> Phoenix.Component.assign(:current_user, user)
     |> Phoenix.Component.assign(:authenticated?, not is_nil(user))}
  end

  @spec fetch_current_user(Plug.Conn.t(), opts()) :: Plug.Conn.t()
  def fetch_current_user(conn, _opts) do
    user = get_session(conn, :current_user)

    conn
    |> assign(:current_user, user)
    |> assign(:authenticated?, not is_nil(user))
  end

  @spec require_auth(Plug.Conn.t(), opts()) :: Plug.Conn.t()
  def require_auth(%{params: %{"code" => _}} = conn, opts) do
    opts = Application.get_all_env(:nym) |> Keyword.merge(opts)

    endpoint = Keyword.fetch!(opts, :on)
    client_id = Phoenix.Controller.endpoint_module(conn).url()
    redirect_uri = get_session(conn, :redirect_uri, "/")

    with {:ok, state} <- validate_param(conn.params["state"], "state"),
         {:ok, me} <- validate_param(conn.params["me"], "me"),
         {:ok, code} <- validate_param(conn.params["code"], "code"),
         {:ok, iss} <- validate_param(conn.params["iss"], "iss"),
         {:ok, session_state} <- validate_session(conn, :state),
         {:ok, code_verifier} <- validate_session(conn, :code_verifier),
         :ok <- validate_state_match(state, session_state),
         :ok <- validate_issuer(iss, endpoint) do
      token_params = %{
        grant_type: "authorization_code",
        me: me,
        code: code,
        client_id: client_id,
        redirect_uri: redirect_uri,
        code_verifier: code_verifier
      }

      case verify_code(endpoint, token_params) do
        {:ok, %{"me" => _, "meta" => meta}} ->
          conn
          |> renew_session()
          |> put_session(:current_user, meta)
          |> redirect(to: URI.parse(redirect_uri).path)
          |> halt()

        {:ok, %{"meta" => _}} ->
          handle_error(conn, "Missing 'me' value")

        {:ok, %{"me" => _}} ->
          handle_error(conn, "Missing 'meta' value")

        {:error, reason} ->
          handle_error(conn, format_error(reason))
      end
    else
      {:error, message} ->
        handle_error(conn, message)
    end
  end

  @spec require_auth(Plug.Conn.t(), opts()) :: Plug.Conn.t()
  def require_auth(conn, opts) do
    opts = Application.get_all_env(:nym) |> Keyword.merge(opts) |> dbg()

    endpoint = Keyword.fetch!(opts, :on)
    client_id = Phoenix.Controller.endpoint_module(conn).url()
    redirect_uri = Phoenix.Controller.current_url(conn)
    scopes = Keyword.get(opts, :scopes, ~w(create update delete media))

    if conn.assigns.current_user do
      conn
    else
      state = Phoenix.Token.sign(conn, "nym_state", System.system_time())
      code_verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
      code_challenge = Base.url_encode64(:crypto.hash(:sha256, code_verifier), padding: false)

      auth_params = %{
        client_id: client_id,
        redirect_uri: redirect_uri,
        state: state,
        code_challenge: code_challenge,
        code_challenge_method: "S256",
        scope: Enum.join(scopes, " ")
      }

      conn
      |> renew_session()
      |> put_session(:state, state)
      |> put_session(:code_verifier, code_verifier)
      |> put_session(:redirect_uri, redirect_uri)
      |> redirect(external: construct_url(endpoint, auth_params))
      |> halt()
    end
  end

  defp construct_url(endpoint, params) do
    query = URI.encode_query(params)

    endpoint
    |> URI.parse()
    |> Map.put(:query, query)
    |> URI.to_string()
  end

  defp verify_code(endpoint, params) do
    opts = [
      url: endpoint,
      form: params,
      headers: [{"Accept", "application/json"}],
      retry: :transient
    ]

    case Req.post(opts) do
      {:ok, %Req.Response{status: 200, body: %{"error" => _} = body}} ->
        {:error, {:token_error, body}}

      {:ok, %Req.Response{status: 200, body: body}} ->
        {:ok, body}

      {:ok, %Req.Response{status: status, body: body}} ->
        {:error, {:http_error, status, body}}

      {:error, reason} ->
        {:error, {:net_error, reason}}
    end
  end

  defp validate_param(nil, name), do: {:error, "Missing '#{name}' parameter"}
  defp validate_param(value, _name), do: {:ok, value}

  defp validate_session(conn, key) do
    case get_session(conn, key) do
      nil -> {:error, "Missing #{key} in session"}
      value -> {:ok, value}
    end
  end

  defp validate_state_match(state, session_state) when state == session_state, do: :ok
  defp validate_state_match(_, _), do: {:error, "Invalid state parameter"}

  defp validate_issuer(iss, expected) when iss == expected, do: :ok
  defp validate_issuer(_, _), do: {:error, "Invalid issuer"}

  defp handle_error(conn, message) do
    Logger.warning("Nym crashed: #{message}")

    conn
    |> put_status(:unauthorized)
    |> put_flash(:error, message)
    |> json(%{error: message})
    |> halt()
  end

  defp format_error({:http_error, status, body}) do
    case body do
      %{"error" => error} -> error
      e when is_binary(e) -> e
      _ -> "Token endpoint returned HTTP #{status}: #{inspect(body)}"
    end
  end

  defp format_error({:token_error, reason}) do
    case reason do
      %{"error_description" => error} -> error
      %{"error" => error} -> error
      e when is_binary(e) -> e
      _ -> "Token endpoint refused request with: #{inspect(reason)}"
    end
  end

  defp format_error({:net_error, reason}) do
    "Connection to token endpoint could not be established: #{inspect(reason)}"
  end

  defp format_error(other) do
    "Something went wrong: #{inspect(other)}"
  end

  # This function renews the session ID and erases the whole
  # session to avoid fixation attacks. If there is any data
  # in the session you may want to preserve after log in/log out,
  # you must explicitly fetch the session data before clearing
  # and then immediately set it after clearing.
  defp renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
  end
end
