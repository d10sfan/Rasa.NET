﻿namespace Rasa.Packets.Social.Client
{
    using Data;
    using Memory;

    public class AddIgnorePacket : ClientPythonPacket
    {
        public override GameOpcode Opcode => GameOpcode.AddIgnore;

        public uint AccountId { get; set; }

        public override void Read(PythonReader pr)
        {
            pr.ReadTuple();
            AccountId = pr.ReadUInt();
        }
    }
}
