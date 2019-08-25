defmodule Protob2 do
  import Bitwise

  def decode_varint(a) do
    decode_varint(a, 0, 0)
  end

  def decode_varint(a, acc, count) do
    case a do
      <<1::integer-size(1), l::integer-size(7), rest::binary>> ->
        # IO.puts "continue flag on "
        decode_varint(rest, (l <<< (count * 7)) + acc, count + 1)

      <<0::integer-size(1), l::integer-size(7), rest::binary>> ->
        # IO.puts "continue flag off "
        {:ok, (l <<< (count * 7)) + acc, rest}

      _ ->
        {:error, {:unknown, a}}
    end
  end

  def protob(data, skip \\ 14)
  def protob(data, skip) when is_list(data), do: protob(:binary.list_to_bin(data), skip)

  def protob(data, skip) do
    protob1(data, [], [], skip, 0)
  end

  def protob1("", group, _roll, _skip, _level) do
    {Enum.reverse(group), ""}
  end

  def protob1(data, group, roll, skip, level) do
    roll = if byte_size(data) == skip and level == 0, do: [{group, data} | roll], else: roll

    case protob2(data, skip, level) do
      {:return, rest} when level == 0 ->
        protob1(rest, group, roll, skip, level)
      {:return, rest} ->
        {:ok, Enum.reverse(group), rest}
      {:error, _} ->
        case roll do
          [{g, d} | _] ->
            {Enum.reverse(g), d}
          _ when level == 0 ->
            {[], data}
          _ ->
            {:error, {:roll, data}}
        end

      {{vtype, vtag, _} = v, rest} when level == 0 and length(roll) > 0 ->
        case List.keyfind(group, vtag, 1) do
          nil ->
            protob1(rest, [v | group], roll, skip, level)
          {^vtype, _, _} ->
            protob1(rest, [v | group], roll, skip, level)
          _ ->
            case roll do
              [{g, d} | _] ->
                {Enum.reverse(g), d}
              _ ->
                {:error, {:roll, data}}
            end
        end

      {v, rest} ->
        protob1(rest, [v | group], roll, skip, level)
    end
  end

  def protob2(data, skip, level) do
    case data do
      # varint
      <<tag::size(5), 0::size(3), rest::binary>> = buf ->
        if (tag &&& 16) == 16 do
          case decode_varint(rest) do
            {:ok, ntag, rest} ->
              tag = (ntag <<< 4) + (tag &&& 0xF)
              case decode_varint(rest) do
                {:ok, n, rest} ->
                  {{:varint, tag, n}, rest}
                _ ->
                  {:error, {:varint, buf}}
              end
            _ ->
              {:error, {:varint, buf}}
          end
        else
          case decode_varint(rest) do
            {:ok, n, rest} ->
              {{:varint, tag, n}, rest}
            _ ->
              {:error, {:varint, buf}}
          end
        end

      # int64
      <<tag::size(5), 1::size(3), rest::binary>> = buf ->
        if (tag &&& 16) == 16 do
          case decode_varint(rest) do
            {:ok, ntag, rest} ->
              tag = (ntag <<< 4) + (tag &&& 0xF)
              case rest do
                <<d::binary-size(8), rest::binary>> ->
                  {{:int64, tag, d}, rest}
                _ ->
                  {:error, {:varint, buf}}
              end
            _ ->
              {:error, {:varint, buf}}
          end
        else
          case rest do
            <<d::binary-size(8), rest::binary>> ->
              {{:int64, tag, d}, rest}
            _ ->
              {:error, {:varint, buf}}
          end
        end

      # binary
      <<tag::size(5), 2::size(3), rest::binary>> = buf ->
        if (tag &&& 16) == 16 do
          case decode_varint(rest) do
            {:ok, ntag, rest} ->
              tag = (ntag <<< 4) + (tag &&& 0xF)
              case decode_varint(rest) do
                {:ok, n, rest} ->
                  case rest do
                    <<d::binary-size(n), rest::binary>> ->
                      {{:binary, tag, d}, rest}

                    _ ->
                      {:error, {:binary, buf}}
                  end
                _ ->
                  {:error, {:binary, buf}}
              end
            _ ->
              {:error, {:int64, buf}}
          end
        else
          case decode_varint(rest) do
            {:ok, n, rest} ->
              case rest do
                <<d::binary-size(n), rest::binary>> ->
                  {{:binary, tag, d}, rest}
                _ ->
                  {:error, {:binary, buf}}
              end
            _ ->
              {:error, {:binary, buf}}
          end
        end

      # group
      <<tag::size(5), 3::size(3), rest::binary>> = buf ->
        if (tag &&& 16) == 16 do
          case decode_varint(rest) do
            {:ok, ntag, rest} ->
              tag = (ntag <<< 4) + (tag &&& 0xF)
              case protob1(rest, [], [], skip, level + 1) do
                {:ok, g, rest} ->
                  {{:group, tag, g}, rest}
                _ ->
                  {:error, {:group, buf}}
              end
            _ ->
              {:error, {:group, buf}}
          end
        else
          case protob1(rest, [], [], skip, level + 1) do
            {:ok, g, rest} ->
              {{:group, tag, g}, rest}
            _ ->
              {:error, {:group, buf}}
          end
        end

      # group end
      <<tag::size(5), 4::size(3), rest::binary>> = buf ->
        if (tag &&& 16) == 16 do
          case decode_varint(rest) do
            {:ok, _, rest} ->
              {:return, rest}
            _ ->
              {:error, {:group, buf}}
          end
        else
          {:return, rest}
        end

      # int32/float32
      <<tag::size(5), 5::size(3), rest::binary>> = buf ->
        if (tag &&& 16) == 16 do
          case decode_varint(rest) do
            {:ok, ntag, rest1} ->
              tag1 = (ntag <<< 4) + (tag &&& 0xF)
              case rest1 do
                <<d::binary-size(4), rest::binary>> ->
                  {{:int32, tag1, d}, rest}
                _ ->
                  {:error, {:int32, buf}}
              end
            _ ->
              {:error, {:int32, buf}}
          end
        else
          case rest do
            <<d::binary-size(4), rest::binary>> ->
              {{:int32, tag, d}, rest}
            _ ->
              {:error, {:int32, buf}}
          end
        end
      # unsupported
      <<_tag::size(5), _opcode::size(3), _rest::binary>> = buf ->
        {:error, {:unknown, buf}}
    end
  end

  def encode_varint(num) do
    encode_varint(num, "")
  end

  def encode_varint(num, acc) do
    case num > 127 do
      true ->
        <<r::integer-size(1)-little, n::integer-size(7)-little>> = <<num::integer-size(8)-little>>
        acc = acc <> <<1::integer-size(1), n::integer-size(7)>>
        encode_varint((num >>> 8 <<< 1) + r, acc)

      false ->
        acc <> <<0::integer-size(1), num::integer-size(7)>>
    end
  end

  def encode(data) do
    encode(data, "")
  end

  def encode([], acc) do
    acc
  end

  def encode([data | rest], acc) do
    acc =
      case data do
        {:varint, tag, n} ->
          acc <> encode_tag(tag, 0) <> encode_varint(n)

        {:int64, tag, n} when is_integer(n) ->
          acc <> encode_tag(tag, 1) <> <<n::size(64)>>

        {:int64, tag, n} ->
          acc <> encode_tag(tag, 1) <> n

        {:binary, tag, n} ->
          acc <> encode_tag(tag, 2) <> encode_varint(byte_size(n)) <> n

        {:group, tag, n} ->
          acc <> encode_tag(tag, 3) <> encode(n) <> encode_tag(tag, 4)

        {:int32, tag, n} ->
          # IO.inspect {acc, encode_tag(tag, 5), n}
          acc <> encode_tag(tag, 5) <> n
      end
    encode(rest, acc)
  end

  def encode_tag(tag, opcode) do
    if tag < 16 do
      <<tag::size(5), opcode::size(3)>>
    else
      btag = (tag &&& 0xF) ||| 0x10
      <<btag::size(5), opcode::size(3)>> <> encode_varint(tag >>> 4)
    end
  end

  def to_map(pb, recursive\\ true) do
    Enum.reduce(pb, %{}, fn {type, index, val}, acc ->
      val =
        case type do
          :group when recursive == true ->
            to_map(val)
          _ ->
            val
        end
      acc =
        case Map.get(acc, index) do
          nil ->
            Map.put(acc, index, val)
          x when is_list(x) ->
            Map.put(acc, index, x ++ [val])
          x ->
            Map.put(acc, index, [x, val])
        end
      acc
    end)
  end

  def get_value(proto_data, tag_value, default \\ nil) when is_list(proto_data) do
    case List.keyfind(proto_data, tag_value, 1) do
      {_type, _tag, value} -> value
      _ -> default
    end
  end
end
