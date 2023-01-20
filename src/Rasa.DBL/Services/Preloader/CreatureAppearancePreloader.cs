﻿using System.Collections.Generic;
using Microsoft.EntityFrameworkCore.Migrations;

namespace Rasa.Services.Preloader
{

    using Structures.World;

    public class CreatureAppearancePreloader : PreloaderBase, IPreloader
    {
        public void Preload(MigrationBuilder migrationBuilder)
        {
            Insert(migrationBuilder, CreatureAppearanceEntry.TableName, typeof(CreatureAppearanceEntry));
        }

        protected override IEnumerable<object[]> GetRows()
        {
            yield return new object[] { 1, 17, 24019, 4286886614 };
            yield return new object[] { 3, 17, 24019, 4286886614 };
            yield return new object[] { 4, 17, 7508, 4286886614 };
            yield return new object[] { 5, 17, 20824, 4286886614 };
            yield return new object[] { 6, 17, 20824, 4286886614 };
            yield return new object[] { 6, 14, 3672, 55555 };
            yield return new object[] { 5, 2, 10000068, 65644 };
            yield return new object[] { 7, 17, 7508, 4286886614 };
            yield return new object[] { 8, 18, 7508, 1111 };
            yield return new object[] { 8, 19, 7508, 1111 };
            yield return new object[] { 100, 17, 24019, 4286886614 };
            yield return new object[] { 100, 16, 4023, 13933202 };
            yield return new object[] { 100, 15, 4022, 933202 };
            yield return new object[] { 100, 3, 4021, 22120 };
            yield return new object[] { 100, 14, 3672, 14404004 };
            yield return new object[] { 100, 13, 27120, 1 };
            yield return new object[] { 10, 17, 24019, 4286886614 };
            yield return new object[] { 10, 14, 3672, 1440400 };
            yield return new object[] { 10, 2, 3941, 12429948 };
            yield return new object[] { 10, 15, 3942, 12429948 };
            yield return new object[] { 10, 16, 3943, 12429948 };
            yield return new object[] { 11, 17, 24019, 4286886614 };
            yield return new object[] { 12, 17, 24019, 4286886614 };
            yield return new object[] { 13, 17, 24019, 4286886614 };
            yield return new object[] { 14, 17, 24019, 4286886614 };
            yield return new object[] { 15, 17, 24019, 4286886614 };
            yield return new object[] { 16, 17, 24019, 4286886614 };
            yield return new object[] { 17, 17, 24019, 4286886614 };
            yield return new object[] { 18, 17, 24019, 4286886614 };
            yield return new object[] { 19, 17, 24019, 4286886614 };
            yield return new object[] { 21, 17, 24019, 4286886614 };
            yield return new object[] { 20, 17, 24019, 4286886614 };
            yield return new object[] { 24, 17, 24019, 4286886614 };
            yield return new object[] { 22, 17, 24019, 4286886614 };
            yield return new object[] { 25, 17, 24019, 4286886614 };
            yield return new object[] { 23, 17, 24019, 4286886614 };
            yield return new object[] { 26, 17, 24019, 4286886614 };
            yield return new object[] { 27, 17, 24019, 4286886614 };
            yield return new object[] { 28, 17, 24019, 4286886614 };
            yield return new object[] { 29, 17, 24019, 4286886614 };
            yield return new object[] { 101, 13, 27120, 1 };
            yield return new object[] { 101, 3, 4021, 22120 };
            yield return new object[] { 101, 15, 4022, 13933202 };
            yield return new object[] { 101, 16, 4023, 13933202 };
            yield return new object[] { 101, 14, 3672, 1 };
            yield return new object[] { 101, 17, 20824, 4286886614 };
            yield return new object[] { 11, 16, 7053, 4444 };
            yield return new object[] { 12, 16, 15632, 1440400 };
            yield return new object[] { 13, 16, 3666, 1111 };
            yield return new object[] { 14, 16, 3811, 1111 };
            yield return new object[] { 15, 16, 3943, 22120 };
            yield return new object[] { 16, 16, 4022, 22120 };
            yield return new object[] { 17, 16, 4028, 55555 };
            yield return new object[] { 18, 16, 4302, 55555 };
            yield return new object[] { 19, 16, 4387, 65644 };
            yield return new object[] { 20, 16, 7496, 65644 };
            yield return new object[] { 21, 16, 19030, 80000 };
            yield return new object[] { 22, 16, 19245, 80000 };
            yield return new object[] { 23, 16, 19250, 266553 };
            yield return new object[] { 24, 16, 19255, 266553 };
            yield return new object[] { 25, 16, 19285, 12429948 };
            yield return new object[] { 26, 16, 19403, 12429948 };
            yield return new object[] { 27, 16, 19412, 977764 };
            yield return new object[] { 28, 16, 19555, 977764 };
            yield return new object[] { 29, 16, 19570, 1440400 };
            yield return new object[] { 11, 15, 7052, 4444 };
            yield return new object[] { 12, 15, 15662, 1440400 };
            yield return new object[] { 13, 15, 3668, 1111 };
            yield return new object[] { 14, 15, 3809, 1111 };
            yield return new object[] { 15, 15, 3942, 22120 };
            yield return new object[] { 16, 15, 4023, 22120 };
            yield return new object[] { 17, 15, 4027, 55555 };
            yield return new object[] { 18, 15, 4301, 55555 };
            yield return new object[] { 19, 15, 4386, 65644 };
            yield return new object[] { 20, 15, 7495, 65644 };
            yield return new object[] { 21, 15, 19076, 80000 };
            yield return new object[] { 22, 15, 19286, 80000 };
            yield return new object[] { 23, 15, 19296, 266553 };
            yield return new object[] { 24, 15, 19301, 266553 };
            yield return new object[] { 25, 15, 19331, 12429948 };
            yield return new object[] { 26, 15, 19425, 429948 };
            yield return new object[] { 27, 15, 19434, 977764 };
            yield return new object[] { 28, 15, 19586, 977764 };
            yield return new object[] { 29, 15, 19611, 1440400 };
            yield return new object[] { 11, 2, 7054, 4444 };
            yield return new object[] { 12, 2, 15692, 1440400 };
            yield return new object[] { 13, 2, 3670, 1111 };
            yield return new object[] { 14, 2, 3810, 1111 };
            yield return new object[] { 15, 2, 3941, 22120 };
            yield return new object[] { 16, 2, 4021, 22120 };
            yield return new object[] { 17, 2, 4025, 55555 };
            yield return new object[] { 18, 2, 4299, 55555 };
            yield return new object[] { 19, 2, 4385, 65644 };
            yield return new object[] { 20, 2, 7498, 5644 };
            yield return new object[] { 21, 2, 19122, 80000 };
            yield return new object[] { 22, 2, 19332, 80000 };
            yield return new object[] { 23, 2, 19242, 266553 };
            yield return new object[] { 24, 2, 19346, 266553 };
            yield return new object[] { 25, 2, 19352, 12429948 };
            yield return new object[] { 26, 2, 19447, 2429948 };
            yield return new object[] { 27, 2, 19457, 977764 };
            yield return new object[] { 28, 2, 19622, 977764 };
            yield return new object[] { 29, 2, 19647, 1440400 };
            yield return new object[] { 11, 14, 3663, 4444 };
            yield return new object[] { 12, 14, 3672, 1440400 };
            yield return new object[] { 13, 14, 3812, 1111 };
            yield return new object[] { 14, 14, 9355, 1111 };
            yield return new object[] { 15, 14, 9356, 22120 };
            yield return new object[] { 16, 14, 9781, 22120 };
            yield return new object[] { 17, 14, 9782, 55555 };
            yield return new object[] { 18, 14, 9783, 55555 };
            yield return new object[] { 19, 14, 9784, 65644 };
            yield return new object[] { 20, 14, 9784, 65644 };
            yield return new object[] { 21, 14, 9784, 80000 };
            yield return new object[] { 22, 14, 9782, 80000 };
            yield return new object[] { 23, 14, 25255, 266553 };
            yield return new object[] { 24, 14, 25256, 266553 };
            yield return new object[] { 25, 14, 25257, 12429948 };
            yield return new object[] { 26, 14, 26681, 12429948 };
            yield return new object[] { 27, 14, 28440, 977764 };
            yield return new object[] { 28, 14, 28536, 977764 };
            yield return new object[] { 29, 14, 9784, 1440400 };
            yield return new object[] { 30, 14, 9781, 4278655809 };
            yield return new object[] { 30, 17, 24008, 4286690539 };
            yield return new object[] { 30, 13, 6271, 0 };
            yield return new object[] { 30, 15, 4023, 4294934528 };
            yield return new object[] { 30, 16, 4022, 4294934528 };
            yield return new object[] { 30, 2, 4021, 4294934528 };

        }
    }
}